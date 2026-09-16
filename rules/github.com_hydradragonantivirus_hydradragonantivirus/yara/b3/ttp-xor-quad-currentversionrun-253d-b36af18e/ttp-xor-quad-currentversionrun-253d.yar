rule TTP_XOR_QUAD_CurrentVersionRun_253d {
  strings:
    $key_253d = { 76 52 [2] 52 5c [2] 79 70 [2] 57 52 [2] 43 49 [2] 4c 53 [2] 52 4e [2] 50 4f [2] 4b 49 [2] 57 4e [2] 4b 61 }

  condition:
    any of them
}