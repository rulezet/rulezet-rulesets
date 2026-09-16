rule TTP_XOR_QUAD_CurrentVersionRun_612f {
  strings:
    $key_612f = { 32 40 [2] 16 4e [2] 3d 62 [2] 13 40 [2] 07 5b [2] 08 41 [2] 16 5c [2] 14 5d [2] 0f 5b [2] 13 5c [2] 0f 73 }

  condition:
    any of them
}