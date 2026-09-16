rule _20160518_10d4aa3a92f76bb4fce0583e87759990_20160518_158cd7acac1f_1275 {
  meta:
    description = "datamaliciousorder - from files 20160518_10d4aa3a92f76bb4fce0583e87759990.js, 20160518_158cd7acac1fa244c6a22591859ad38c.js, 20160518_2c79e8b4b8532fae2c7866618249bf12.js, 20160518_4bc1502645d020aa6e890489d02276c4.js, 20160518_52dddf013ef3fb2ed104dd35f0961c75.js, 20160518_ba6a79c9fa56a7c01e1cbd7d77e5cd07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7492e94452509a2885f8f224044ad123c3ce95d7168f9c64af6da65d38780391"
    hash2       = "440c7ca6c72c82fd8a66b829deeacfa68e819eaae2abe5ce536d6278eb88180c"
    hash3       = "9fb8037fa3af5a9bff4d56a732fd364228af2145c31051d08dd3c33849df1f1b"
    hash4       = "259a5464a6ac4e6975f801f84bb55f7005d7bcf420cb24bd998cc3285780484f"
    hash5       = "62b0b00899d73e4cab1bddc2b215e25f1ba707874f7e39cc522e2222ba1d65ca"
    hash6       = "f4d4a3607374552414999568cb200ef3026a339e75c7fe4e2bde782e6af72c2f"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* N  */, dingy, (true, false));" fullword ascii
    $s2 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* N  */, A8name /* N  *" ascii
    $s3 = "newtonsCradle1 /* N  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s4 = "function sDiv2(){return newtonsCradle0 /* N  */;};" fullword ascii
    $s5 = "dot1 /* N  */= true;/* N  */" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}