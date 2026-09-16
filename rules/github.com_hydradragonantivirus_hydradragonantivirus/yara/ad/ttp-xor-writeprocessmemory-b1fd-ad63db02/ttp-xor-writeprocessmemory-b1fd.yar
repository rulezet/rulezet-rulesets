rule TTP_XOR_WriteProcessMemory_b1fd {
  strings:
    $key_b1fd = { e6 8f [2] d4 ad [2] d2 98 [2] fc 98 [2] c3 84 }

  condition:
    any of them
}