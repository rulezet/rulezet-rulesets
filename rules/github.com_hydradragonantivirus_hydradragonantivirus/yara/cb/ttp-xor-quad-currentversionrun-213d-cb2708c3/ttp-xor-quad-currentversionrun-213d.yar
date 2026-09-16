rule TTP_XOR_QUAD_CurrentVersionRun_213d {
  strings:
    $key_213d = { 72 52 [2] 56 5c [2] 7d 70 [2] 53 52 [2] 47 49 [2] 48 53 [2] 56 4e [2] 54 4f [2] 4f 49 [2] 53 4e [2] 4f 61 }

  condition:
    any of them
}