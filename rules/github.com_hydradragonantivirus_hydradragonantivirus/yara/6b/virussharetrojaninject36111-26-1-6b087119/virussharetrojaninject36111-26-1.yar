rule VirusShareTrojanInject36111_26_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanInject36111_26_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c31c4fbaa4b7a4f9667cc17a3c12cedc9605bc86ebd1934c084a8626eea92da7"

  strings:
    $s1  = "DELETE FROM cookies WHERE host_key = '.facebook.com'" fullword ascii
    $s2  = "SELECT creation_utc,host_key,name,value,path,expires_utc,is_secure,is_httponly,last_access_utc,has_expires,is_persistent,priorit" ascii
    $s3  = "Host: www.facebook.com" fullword wide
    $s4  = "login get cookie" fullword ascii
    $s5  = "Origin: https://www.facebook.com" fullword wide
    $s6  = "p_zero_click,generation_upload_status,possible_username_pairs,id,date_last_used,moving_blocked_for FROM logins;" fullword ascii
    $s7  = "SELECT origin_url,action_url,username_element,username_value,password_element,hex(password_value) password_value,submit_element," ascii
    $s8  = "\\Google\\Chrome\\User Data\\Default\\Login Data" fullword wide
    $s9  = "\\Microsoft\\Edge\\User Data\\Default\\Login Data" fullword wide
    $s10 = "SELECT creation_utc,host_key,name,value,path,expires_utc,is_secure,is_httponly,last_access_utc,has_expires,is_persistent,priorit" ascii
    $s11 = "y,hex(encrypted_value) encrypted_value,samesite,source_scheme,source_port,is_same_party FROM cookies;" fullword ascii
    $s12 = "SELECT origin_url,action_url,username_element,username_value,password_element,hex(password_value) password_value,submit_element," ascii
    $s13 = "signon_realm,date_created,blacklisted_by_user,scheme,password_type,times_used,form_data,display_name,icon_url,federation_url,ski" ascii
    $s14 = "Error (WinHttpAddRequestHeaders)" fullword wide
    $s15 = "errorN6J44tEhi cookie empty" fullword ascii
    $s16 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36 Edg/87.0.664." wide
    $s17 = "nMozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36 Edg/87.0.664" wide
    $s18 = "tMozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36 Edg/87.0.664" wide
    $s19 = "eMozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36 Edg/87.0.664" wide
    $s20 = "ager&fields=%5B%22account_id%22%2C%22account_status%22%2C%22is_direct_deals_enabled%22%2C%22business%7Bid%2Cname%7D%22%2C%22view" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}