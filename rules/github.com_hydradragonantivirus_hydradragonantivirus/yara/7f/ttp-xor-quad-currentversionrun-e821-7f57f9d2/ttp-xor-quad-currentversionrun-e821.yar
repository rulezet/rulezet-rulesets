rule TTP_XOR_QUAD_CurrentVersionRun_e821 {
  strings:
    $key_e821 = { bb 4e [2] 9f 40 [2] b4 6c [2] 9a 4e [2] 8e 55 [2] 81 4f [2] 9f 52 [2] 9d 53 [2] 86 55 [2] 9a 52 [2] 86 7d }

  condition:
    any of them
}