rule TTP_XOR_QUAD_CurrentVersionRun_3f7d {
  strings:
    $key_3f7d = { 6c 12 [2] 48 1c [2] 63 30 [2] 4d 12 [2] 59 09 [2] 56 13 [2] 48 0e [2] 4a 0f [2] 51 09 [2] 4d 0e [2] 51 21 }

  condition:
    any of them
}