rule TTP_XOR_QUAD_CurrentVersionRun_103c {
  strings:
    $key_103c = { 43 53 [2] 67 5d [2] 4c 71 [2] 62 53 [2] 76 48 [2] 79 52 [2] 67 4f [2] 65 4e [2] 7e 48 [2] 62 4f [2] 7e 60 }

  condition:
    any of them
}