rule TTP_XOR_QUAD_CurrentVersionRun_4b32 {
  strings:
    $key_4b32 = { 18 5d [2] 3c 53 [2] 17 7f [2] 39 5d [2] 2d 46 [2] 22 5c [2] 3c 41 [2] 3e 40 [2] 25 46 [2] 39 41 [2] 25 6e }

  condition:
    any of them
}