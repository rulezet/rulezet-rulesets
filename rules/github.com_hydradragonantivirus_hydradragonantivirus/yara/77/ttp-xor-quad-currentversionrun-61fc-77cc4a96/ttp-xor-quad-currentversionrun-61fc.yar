rule TTP_XOR_QUAD_CurrentVersionRun_61fc {
  strings:
    $key_61fc = { 32 93 [2] 16 9d [2] 3d b1 [2] 13 93 [2] 07 88 [2] 08 92 [2] 16 8f [2] 14 8e [2] 0f 88 [2] 13 8f [2] 0f a0 }

  condition:
    any of them
}