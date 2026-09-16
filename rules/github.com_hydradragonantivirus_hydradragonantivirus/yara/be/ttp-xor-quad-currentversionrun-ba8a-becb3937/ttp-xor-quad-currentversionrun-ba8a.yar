rule TTP_XOR_QUAD_CurrentVersionRun_ba8a {
  strings:
    $key_ba8a = { e9 e5 [2] cd eb [2] e6 c7 [2] c8 e5 [2] dc fe [2] d3 e4 [2] cd f9 [2] cf f8 [2] d4 fe [2] c8 f9 [2] d4 d6 }

  condition:
    any of them
}