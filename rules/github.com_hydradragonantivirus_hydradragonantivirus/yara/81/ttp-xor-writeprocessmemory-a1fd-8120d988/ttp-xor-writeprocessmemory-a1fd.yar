rule TTP_XOR_WriteProcessMemory_a1fd {
  strings:
    $key_a1fd = { f6 8f [2] c4 ad [2] c2 98 [2] ec 98 [2] d3 84 }

  condition:
    any of them
}