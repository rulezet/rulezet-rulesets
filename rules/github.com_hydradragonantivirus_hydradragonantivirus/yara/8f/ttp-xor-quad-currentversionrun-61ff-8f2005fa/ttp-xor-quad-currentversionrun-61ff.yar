rule TTP_XOR_QUAD_CurrentVersionRun_61ff {
  strings:
    $key_61ff = { 32 90 [2] 16 9e [2] 3d b2 [2] 13 90 [2] 07 8b [2] 08 91 [2] 16 8c [2] 14 8d [2] 0f 8b [2] 13 8c [2] 0f a3 }

  condition:
    any of them
}