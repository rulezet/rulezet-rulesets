rule TTP_XOR_QUAD_CurrentVersionRun_e83d {
  strings:
    $key_e83d = { bb 52 [2] 9f 5c [2] b4 70 [2] 9a 52 [2] 8e 49 [2] 81 53 [2] 9f 4e [2] 9d 4f [2] 86 49 [2] 9a 4e [2] 86 61 }

  condition:
    any of them
}