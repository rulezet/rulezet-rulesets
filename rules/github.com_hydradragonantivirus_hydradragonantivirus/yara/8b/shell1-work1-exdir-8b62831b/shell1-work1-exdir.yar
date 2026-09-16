rule shell1_work1_exdir {
  meta:
    description = "work1 - file exdir.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-12-22"
    hash1       = "73910102658eb6291d811d64c3d83cbca948e06050b5bf6c4b8697a115efd6f9"

  strings:
    $x1  = "$shell = file_get_contents('https://pastebin.com/raw/hpqEekGT'); //" fullword ascii
    $s2  = "file_put_contents('wp-system.php',$shell);  //" fullword ascii
    $s3  = "$base = file_get_contents('base');" fullword ascii
    $s4  = "$admin = file_get_contents('admin');" fullword ascii
    $s5  = "$user = posix_getpwuid(posix_getuid());" fullword ascii
    $s6  = "$result=fopen('result.txt','w');" fullword ascii
    $s7  = "copy($file,($i+1).'.txt');" fullword ascii
    $s8  = "$find = 'wp-config.php';" fullword ascii
    $s9  = "$new='wp-system.php';" fullword ascii
    $s10 = "$result = findFilesFromDirectory($finalPath, $files, $find);" fullword ascii
    $s11 = "function findFilesFromDirectory($path, &$files, $find) {" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 3KB and
      (1 of ($x*) and all of them)
    ) or (all of them)
}