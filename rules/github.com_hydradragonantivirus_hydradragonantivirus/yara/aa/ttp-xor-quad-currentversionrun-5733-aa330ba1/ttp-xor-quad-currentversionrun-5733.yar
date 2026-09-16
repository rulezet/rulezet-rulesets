rule TTP_XOR_QUAD_CurrentVersionRun_5733 {
  strings:
    $key_5733 = { 04 5c [2] 20 52 [2] 0b 7e [2] 25 5c [2] 31 47 [2] 3e 5d [2] 20 40 [2] 22 41 [2] 39 47 [2] 25 40 [2] 39 6f }

  condition:
    any of them
}