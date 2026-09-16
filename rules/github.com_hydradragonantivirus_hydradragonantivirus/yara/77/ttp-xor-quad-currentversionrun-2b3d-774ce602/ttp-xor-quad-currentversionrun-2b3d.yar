rule TTP_XOR_QUAD_CurrentVersionRun_2b3d {
  strings:
    $key_2b3d = { 78 52 [2] 5c 5c [2] 77 70 [2] 59 52 [2] 4d 49 [2] 42 53 [2] 5c 4e [2] 5e 4f [2] 45 49 [2] 59 4e [2] 45 61 }

  condition:
    any of them
}