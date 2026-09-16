rule TTP_XOR_QUAD_CurrentVersionRun_a1fd {
  strings:
    $key_a1fd = { f2 92 [2] d6 9c [2] fd b0 [2] d3 92 [2] c7 89 [2] c8 93 [2] d6 8e [2] d4 8f [2] cf 89 [2] d3 8e [2] cf a1 }

  condition:
    any of them
}