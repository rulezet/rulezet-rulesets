rule TTP_XOR_QUAD_CurrentVersionRun_2b3c {
  strings:
    $key_2b3c = { 78 53 [2] 5c 5d [2] 77 71 [2] 59 53 [2] 4d 48 [2] 42 52 [2] 5c 4f [2] 5e 4e [2] 45 48 [2] 59 4f [2] 45 60 }

  condition:
    any of them
}