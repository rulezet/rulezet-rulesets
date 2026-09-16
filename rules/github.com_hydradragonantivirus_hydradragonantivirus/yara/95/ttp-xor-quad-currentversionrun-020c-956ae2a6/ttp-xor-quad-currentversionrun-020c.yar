rule TTP_XOR_QUAD_CurrentVersionRun_020c {
  strings:
    $key_020c = { 51 63 [2] 75 6d [2] 5e 41 [2] 70 63 [2] 64 78 [2] 6b 62 [2] 75 7f [2] 77 7e [2] 6c 78 [2] 70 7f [2] 6c 50 }

  condition:
    any of them
}