rule TTP_XOR_QUAD_CurrentVersionRun_577d {
  strings:
    $key_577d = { 04 12 [2] 20 1c [2] 0b 30 [2] 25 12 [2] 31 09 [2] 3e 13 [2] 20 0e [2] 22 0f [2] 39 09 [2] 25 0e [2] 39 21 }

  condition:
    any of them
}