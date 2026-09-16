rule TTP_XOR_QUAD_CurrentVersionRun_71cd {
  strings:
    $key_71cd = { 22 a2 [2] 06 ac [2] 2d 80 [2] 03 a2 [2] 17 b9 [2] 18 a3 [2] 06 be [2] 04 bf [2] 1f b9 [2] 03 be [2] 1f 91 }

  condition:
    any of them
}