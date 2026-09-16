rule TTP_XOR_QUAD_CurrentVersionRun_e426 {
  strings:
    $key_e426 = { b7 49 [2] 93 47 [2] b8 6b [2] 96 49 [2] 82 52 [2] 8d 48 [2] 93 55 [2] 91 54 [2] 8a 52 [2] 96 55 [2] 8a 7a }

  condition:
    any of them
}