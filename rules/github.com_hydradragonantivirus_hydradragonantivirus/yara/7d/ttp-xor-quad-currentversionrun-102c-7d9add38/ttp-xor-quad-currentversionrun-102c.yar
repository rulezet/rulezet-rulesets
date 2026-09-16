rule TTP_XOR_QUAD_CurrentVersionRun_102c {
  strings:
    $key_102c = { 43 43 [2] 67 4d [2] 4c 61 [2] 62 43 [2] 76 58 [2] 79 42 [2] 67 5f [2] 65 5e [2] 7e 58 [2] 62 5f [2] 7e 70 }

  condition:
    any of them
}