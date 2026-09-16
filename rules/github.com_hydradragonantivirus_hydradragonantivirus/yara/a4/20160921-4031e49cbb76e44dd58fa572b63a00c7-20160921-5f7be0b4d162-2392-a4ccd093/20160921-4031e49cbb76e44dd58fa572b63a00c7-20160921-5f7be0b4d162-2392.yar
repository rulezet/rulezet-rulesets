rule _20160921_4031e49cbb76e44dd58fa572b63a00c7_20160921_5f7be0b4d162_2392 {
  meta:
    description = "datamaliciousorder - from files 20160921_4031e49cbb76e44dd58fa572b63a00c7.js, 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js, 20160921_8c8c9fad8af659443108d1078847a668.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42519dff3fd2ed2dc9bcd0f12a16fe310be93f90efd5d40110f336dc5010d050"
    hash2       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"
    hash3       = "05c35ee4072476c50081705469d125bb2570dea942839cab58bf87874667da59"

  strings:
    $s1 = "k(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"FJs\"" ascii
    $s2 = "on fuck(){return \"Xg\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"" ascii
    $s3 = "{return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Oh\";})(" ascii
    $s4 = "c\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Xg\";})(),(function" ascii
    $s5 = "unction fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){retu" ascii
    $s6 = "n \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s7 = "nction fuck(){return \"CTm\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){retu" ascii
    $s8 = "return \"Fv\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"YAv\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}