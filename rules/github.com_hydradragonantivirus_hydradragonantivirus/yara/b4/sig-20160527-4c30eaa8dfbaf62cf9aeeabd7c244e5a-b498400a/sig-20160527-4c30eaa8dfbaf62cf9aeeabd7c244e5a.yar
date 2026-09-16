rule sig_20160527_4c30eaa8dfbaf62cf9aeeabd7c244e5a {
  meta:
    description = "datamaliciousorder - file 20160527_4c30eaa8dfbaf62cf9aeeabd7c244e5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "472ebe629b1cac6985af38dc3c247bcd80f4ef6ac29f8923e70ac14ccac692b7"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<apAY6dZ767.length;i++)if(i%2==0)x.push(apAY6dZ767[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}