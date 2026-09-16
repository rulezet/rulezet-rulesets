rule TTP_XOR_QUAD_CurrentVersionRun_f312 {
  strings:
    $key_f312 = { a0 7d [2] 84 73 [2] af 5f [2] 81 7d [2] 95 66 [2] 9a 7c [2] 84 61 [2] 86 60 [2] 9d 66 [2] 81 61 [2] 9d 4e }

  condition:
    any of them
}