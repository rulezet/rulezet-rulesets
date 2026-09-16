rule TTP_XOR_QUAD_CurrentVersionRun_eae5 {
  strings:
    $key_eae5 = { b9 8a [2] 9d 84 [2] b6 a8 [2] 98 8a [2] 8c 91 [2] 83 8b [2] 9d 96 [2] 9f 97 [2] 84 91 [2] 98 96 [2] 84 b9 }

  condition:
    any of them
}