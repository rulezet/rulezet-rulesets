rule _20160921_5f7be0b4d162caa40e1fc5a06f9f867a_20160921_a210d5e93bf8_5289 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js, 20160921_a210d5e93bf8b06dbd0a1b262abe210f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"
    hash2       = "681408ae198939a760d376554e62f86e9d1fe2306266ffaee496dc9eed4d0687"

  strings:
    $s1 = "\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fu" ascii
    $s2 = "eturn \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})()," ascii
    $s3 = "(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"UOe\";" ascii
    $s4 = "nction fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s5 = "{return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}