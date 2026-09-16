rule TTP_XOR_QUAD_CurrentVersionRun_103d {
  strings:
    $key_103d = { 43 52 [2] 67 5c [2] 4c 70 [2] 62 52 [2] 76 49 [2] 79 53 [2] 67 4e [2] 65 4f [2] 7e 49 [2] 62 4e [2] 7e 61 }

  condition:
    any of them
}