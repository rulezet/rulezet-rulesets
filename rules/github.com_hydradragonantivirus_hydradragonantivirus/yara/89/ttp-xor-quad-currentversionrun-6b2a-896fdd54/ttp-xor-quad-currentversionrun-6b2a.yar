rule TTP_XOR_QUAD_CurrentVersionRun_6b2a {
  strings:
    $key_6b2a = { 38 45 [2] 1c 4b [2] 37 67 [2] 19 45 [2] 0d 5e [2] 02 44 [2] 1c 59 [2] 1e 58 [2] 05 5e [2] 19 59 [2] 05 76 }

  condition:
    any of them
}