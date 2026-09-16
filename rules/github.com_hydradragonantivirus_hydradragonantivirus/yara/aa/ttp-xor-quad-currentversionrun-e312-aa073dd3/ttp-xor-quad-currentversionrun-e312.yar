rule TTP_XOR_QUAD_CurrentVersionRun_e312 {
  strings:
    $key_e312 = { b0 7d [2] 94 73 [2] bf 5f [2] 91 7d [2] 85 66 [2] 8a 7c [2] 94 61 [2] 96 60 [2] 8d 66 [2] 91 61 [2] 8d 4e }

  condition:
    any of them
}