rule TTP_XOR_QUAD_CurrentVersionRun_e412 {
  strings:
    $key_e412 = { b7 7d [2] 93 73 [2] b8 5f [2] 96 7d [2] 82 66 [2] 8d 7c [2] 93 61 [2] 91 60 [2] 8a 66 [2] 96 61 [2] 8a 4e }

  condition:
    any of them
}