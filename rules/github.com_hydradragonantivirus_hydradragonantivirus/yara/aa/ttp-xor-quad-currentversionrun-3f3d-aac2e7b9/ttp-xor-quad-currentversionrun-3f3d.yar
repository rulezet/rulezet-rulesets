rule TTP_XOR_QUAD_CurrentVersionRun_3f3d {
  strings:
    $key_3f3d = { 6c 52 [2] 48 5c [2] 63 70 [2] 4d 52 [2] 59 49 [2] 56 53 [2] 48 4e [2] 4a 4f [2] 51 49 [2] 4d 4e [2] 51 61 }

  condition:
    any of them
}