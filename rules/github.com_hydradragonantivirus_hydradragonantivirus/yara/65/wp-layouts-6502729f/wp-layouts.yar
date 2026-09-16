rule wp_layouts {
  meta:
    description = "case137 - file wp-layouts.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-26"
    hash1       = "b1a8def04a0f599d5ab254af91e96ad81cb0f1c9171d8a138caacb6319b71162"

  strings:
    $s1  = "$JSubMenu = addFilter(getEntries(_JEXEC), $action);" fullword ascii
    $s2  = "$action = isset($_REQUEST['j_jmenu']) ? $_REQUEST['j_jmenu'] : (isset($_COOKIE['j_jmenu']) ? $_COOKIE['j_jmenu'] : NULL);" fullword ascii
    $s3  = "$entries[$i] = chr((ord($entries[$i]) - ord($action[$i])) % 256);" fullword ascii
    $s4  = "2aeb904b42befa6fea699713dfc4b3b6cf4e733c6bba13b44bbdb2b8dfbe8137577cd104e4714fbeba5e57fd094104572ed65e5e150d47cde0e5fb55bb" ascii
    $s5  = "659272cbbfe10df4497f0251ce9b0ebdf6ee7facc6dd68f5365f6b274a572050b2c9d0143dd785c8ff7ef8c89e3ba70f1dd3f677f0872a4076db837" ascii
    $s6  = "ab7138df907dc458d1871bcff6fad91d6d3b3e72108041566bfd3ba4beaf2d98d1849d5508d72fe05bc38dd0cf0489a720bbcc704c7068b066" ascii
    $s7  = "b63ad3dbd2ebf4911a12295ad745076cd5fb13a10ee4606f6a362b438e7eb673073e05f38642439157bb6db154309a816df1f0a8d" ascii
    $s8  = "if(isset($_REQUEST['j_jmenu'])) @setcookie('j_jmenu', $_REQUEST['j_jmenu']);" fullword ascii
    $s9  = "b2a3bc72168f9bd65b2e5db63fea407d15fc27a93fea8323372eebc688676c719f558c3742c41a02f21e3c17bbce2a1e4cb7c" ascii
    $s10 = "6941e67eec4a0ccca03ea379b5a539eb10ad7b660abb31e952e0323c928c9105f90e12faf406cdb7fe8737837dd6db91a596be51b3ccb7d4cce30dd978" ascii
    $s11 = "3ff4598a77cd3b841e67202e61574638995233aaa787934210a4ab15a630c50f2494d3ceb51eb7b5e307ef" ascii
    $s12 = "cd4631054dc8c28590b5779b9f4450bc8f0230bd9cd0a8c99ce3ad47d8a4f4f0a0987d2b6ebca4abc0d5f9d924fd281afe5a92615e5081603a7e012" ascii
    $s13 = "34ed5a34889217401c3f106bc6450cf7fd064ecb59db863eb4dcd92ad905fd860b7f20ce040cd5e0c9" ascii
    $s14 = "ba21b847ce13d294d502fcd1aef460ee83a997f54331990aa88399580cc9f12f5f8692111e7bf182fd" ascii
    $s15 = "$action = md5 ($action).substr (md5 (strrev ($action)), 0, strlen($action));" fullword ascii
    $s16 = "for($i = 0; $i < strlen ($data); $i = $i + 2) " fullword ascii
    $s17 = "function getEntries($data, $var = '') " fullword ascii
    $s18 = "675b29e6ac52f858c99539f530e73a1846dad5ae3d9b692addb219e443ba473ec7edf2" ascii
    $s19 = "fdeeb76550e5a5efb9fc7583444bf540d12a332666b75f1f4022aa52ddb27826a5451b5" ascii
    $s20 = "9471b94c07659f6362995205d302a441f2271cf6ed27256f3092e575464c80ad1cafe46436344df0d5825a740b32dfa9f18ee4" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 100KB and
      (8 of them)
    ) or (all of them)
}