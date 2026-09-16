rule TTP_XOR_QUAD_CurrentVersionRun_3b32 {
  strings:
    $key_3b32 = { 68 5d [2] 4c 53 [2] 67 7f [2] 49 5d [2] 5d 46 [2] 52 5c [2] 4c 41 [2] 4e 40 [2] 55 46 [2] 49 41 [2] 55 6e }

  condition:
    any of them
}