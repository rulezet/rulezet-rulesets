rule TTP_XOR_QUAD_CurrentVersionRun_a1ab {
  strings:
    $key_a1ab = { f2 c4 [2] d6 ca [2] fd e6 [2] d3 c4 [2] c7 df [2] c8 c5 [2] d6 d8 [2] d4 d9 [2] cf df [2] d3 d8 [2] cf f7 }

  condition:
    any of them
}