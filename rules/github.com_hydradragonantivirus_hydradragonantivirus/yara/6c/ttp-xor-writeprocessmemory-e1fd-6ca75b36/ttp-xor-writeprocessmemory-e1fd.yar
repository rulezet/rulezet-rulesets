rule TTP_XOR_WriteProcessMemory_e1fd {
  strings:
    $key_e1fd = { b6 8f [2] 84 ad [2] 82 98 [2] ac 98 [2] 93 84 }

  condition:
    any of them
}