rule TTP_XOR_QUAD_CurrentVersionRun_f826 {
  strings:
    $key_f826 = { ab 49 [2] 8f 47 [2] a4 6b [2] 8a 49 [2] 9e 52 [2] 91 48 [2] 8f 55 [2] 8d 54 [2] 96 52 [2] 8a 55 [2] 96 7a }

  condition:
    any of them
}