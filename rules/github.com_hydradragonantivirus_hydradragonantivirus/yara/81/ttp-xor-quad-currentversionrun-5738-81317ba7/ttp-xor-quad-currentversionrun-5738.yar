rule TTP_XOR_QUAD_CurrentVersionRun_5738 {
  strings:
    $key_5738 = { 04 57 [2] 20 59 [2] 0b 75 [2] 25 57 [2] 31 4c [2] 3e 56 [2] 20 4b [2] 22 4a [2] 39 4c [2] 25 4b [2] 39 64 }

  condition:
    any of them
}