rule blackenergy3_api_encode
{
    meta:
        author = "Mike Schladt"
        date = "2015-06-08"
        description = "matches api name encoding function for be3 persistence dll"
        md5 = "46649163C659CBA8A7D0D4075329EFA3"
        reference  = "https://www.f-secure.com/documents/996508/1030745/blackenergy_whitepaper.pdf"
        
    strings:
        $api_encode = {8B C2 C1 E8 09 32 E0 32 C4 32 E0 0F C8 66 8B CA 66 D1 E9 8A E1 33 C9 8A EA 66 D1 E9 8A C1 8B CA D1 E9 0F C9 0A C1 33 C9 8A 0B 33 C1 8B D0 43 EB CA}
        
    condition:
        $api_encode
        
}