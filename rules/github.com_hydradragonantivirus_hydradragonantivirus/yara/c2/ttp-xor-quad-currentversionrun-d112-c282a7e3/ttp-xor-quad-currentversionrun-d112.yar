rule TTP_XOR_QUAD_CurrentVersionRun_d112 {
  strings:
    $key_d112 = { 82 7d [2] a6 73 [2] 8d 5f [2] a3 7d [2] b7 66 [2] b8 7c [2] a6 61 [2] a4 60 [2] bf 66 [2] a3 61 [2] bf 4e }

  condition:
    any of them
}