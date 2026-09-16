rule TTP_XOR_QUAD_CurrentVersionRun_eaf8 {
  strings:
    $key_eaf8 = { b9 97 [2] 9d 99 [2] b6 b5 [2] 98 97 [2] 8c 8c [2] 83 96 [2] 9d 8b [2] 9f 8a [2] 84 8c [2] 98 8b [2] 84 a4 }

  condition:
    any of them
}