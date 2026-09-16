rule TTP_XOR_QUAD_CurrentVersionRun_71e3 {
  strings:
    $key_71e3 = { 22 8c [2] 06 82 [2] 2d ae [2] 03 8c [2] 17 97 [2] 18 8d [2] 06 90 [2] 04 91 [2] 1f 97 [2] 03 90 [2] 1f bf }

  condition:
    any of them
}