rule TTP_XOR_QUAD_CurrentVersionRun_ba01 {
  strings:
    $key_ba01 = { e9 6e [2] cd 60 [2] e6 4c [2] c8 6e [2] dc 75 [2] d3 6f [2] cd 72 [2] cf 73 [2] d4 75 [2] c8 72 [2] d4 5d }

  condition:
    any of them
}