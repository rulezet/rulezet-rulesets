rule TTP_XOR_QUAD_CurrentVersionRun_097d {
  strings:
    $key_097d = { 5a 12 [2] 7e 1c [2] 55 30 [2] 7b 12 [2] 6f 09 [2] 60 13 [2] 7e 0e [2] 7c 0f [2] 67 09 [2] 7b 0e [2] 67 21 }

  condition:
    any of them
}