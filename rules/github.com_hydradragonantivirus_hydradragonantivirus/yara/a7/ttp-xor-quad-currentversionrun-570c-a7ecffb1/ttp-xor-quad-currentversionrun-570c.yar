rule TTP_XOR_QUAD_CurrentVersionRun_570c {
  strings:
    $key_570c = { 04 63 [2] 20 6d [2] 0b 41 [2] 25 63 [2] 31 78 [2] 3e 62 [2] 20 7f [2] 22 7e [2] 39 78 [2] 25 7f [2] 39 50 }

  condition:
    any of them
}