rule TTP_XOR_QUAD_CurrentVersionRun_eae9 {
  strings:
    $key_eae9 = { b9 86 [2] 9d 88 [2] b6 a4 [2] 98 86 [2] 8c 9d [2] 83 87 [2] 9d 9a [2] 9f 9b [2] 84 9d [2] 98 9a [2] 84 b5 }

  condition:
    any of them
}