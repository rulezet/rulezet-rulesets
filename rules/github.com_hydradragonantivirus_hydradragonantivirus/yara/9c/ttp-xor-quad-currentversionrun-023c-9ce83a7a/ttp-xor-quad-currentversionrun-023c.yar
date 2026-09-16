rule TTP_XOR_QUAD_CurrentVersionRun_023c {
  strings:
    $key_023c = { 51 53 [2] 75 5d [2] 5e 71 [2] 70 53 [2] 64 48 [2] 6b 52 [2] 75 4f [2] 77 4e [2] 6c 48 [2] 70 4f [2] 6c 60 }

  condition:
    any of them
}