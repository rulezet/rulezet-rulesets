rule sig_20160301_b9fabd8fb7ec620295c232fa978b88f8 {
  meta:
    description = "datamaliciousorder - file 20160301_b9fabd8fb7ec620295c232fa978b88f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbd9e9038bf5959e134ee55ebd6b8c802ee56c54d987a85441f33b361be3ace2"

  strings:
    $s1 = "while(legendPreservative[(\"\\u0063on\\u0074\\u0065\\u0078\\u0074\", \"s\\u0070\\u0069r\\u0061l\", \"manife\\u0073\\u0074\\u006f" ascii
    $s2 = "while(legendPreservative[(\"\\u0063on\\u0074\\u0065\\u0078\\u0074\", \"s\\u0070\\u0069r\\u0061l\", \"manife\\u0073\\u0074\\u006f" ascii
    $s3 = "recipeRegulate[(\"anon\\u0079m\\u006f\\u0075s\", \"\\u006doral\", function String.prototype.bandTransmission() {" fullword ascii
    $s4 = "theoryAdaptation = (((53 ^ 100), (3000 / 15), (1122 / 22), (480 / 3)), this);" fullword ascii
    $s5 = "} catch(boxingAssistant) {};" fullword ascii

  condition:
    uint16(0) == 0x6874 and
    all of them
}