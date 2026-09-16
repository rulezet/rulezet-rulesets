rule TTP_XOR_QUAD_CurrentVersionRun_2b32 {
  strings:
    $key_2b32 = { 78 5d [2] 5c 53 [2] 77 7f [2] 59 5d [2] 4d 46 [2] 42 5c [2] 5c 41 [2] 5e 40 [2] 45 46 [2] 59 41 [2] 45 6e }

  condition:
    any of them
}